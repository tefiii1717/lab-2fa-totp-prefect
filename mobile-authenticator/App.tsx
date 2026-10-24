import { CameraView, useCameraPermissions } from 'expo-camera';
import * as SecureStore from 'expo-secure-store';
import { StatusBar } from 'expo-status-bar';
import { useCallback, useEffect, useRef, useState } from 'react';
import {
  Alert,
  FlatList,
  KeyboardAvoidingView,
  Platform,
  Pressable,
  StyleSheet,
  Text,
  TextInput,
  View,
} from 'react-native';

import { PERIOD, isValidBase32Secret, parseOtpAuthUri, secondsRemaining, timeStep, totp } from './src/totp';

interface Account {
  id: string;
  issuer: string;
  account: string;
  secret: string;
}

const STORAGE_KEY = 'totp_accounts';

type Screen = 'list' | 'add' | 'scan';

export default function App() {
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [screen, setScreen] = useState<Screen>('list');
  const now = useClock();

  useEffect(() => {
    SecureStore.getItemAsync(STORAGE_KEY)
      .then((raw) => raw && setAccounts(JSON.parse(raw)))
      .catch(() => Alert.alert('Error', 'No se pudieron leer las cuentas guardadas'));
  }, []);

  const persist = useCallback((next: Account[]) => {
    setAccounts(next);
    SecureStore.setItemAsync(STORAGE_KEY, JSON.stringify(next)).catch(() =>
      Alert.alert('Error', 'No se pudo guardar la cuenta en el almacenamiento seguro')
    );
  }, []);

  const addAccount = (data: Omit<Account, 'id'>) => {
    persist([...accounts, { ...data, id: `${Date.now()}` }]);
    setScreen('list');
  };

  const removeAccount = (account: Account) =>
    Alert.alert('Eliminar cuenta', `¿Eliminar ${account.issuer}: ${account.account}?`, [
      { text: 'Cancelar', style: 'cancel' },
      { text: 'Eliminar', style: 'destructive', onPress: () => persist(accounts.filter((a) => a.id !== account.id)) },
    ]);

  return (
    <View style={styles.container}>
      <StatusBar style="light" />
      {screen === 'scan' ? (
        <ScanScreen onScanned={addAccount} onCancel={() => setScreen('list')} />
      ) : screen === 'add' ? (
        <AddScreen onAdd={addAccount} onCancel={() => setScreen('list')} onScan={() => setScreen('scan')} />
      ) : (
        <ListScreen accounts={accounts} now={now} onAdd={() => setScreen('add')} onRemove={removeAccount} />
      )}
    </View>
  );
}

/** Reloj local que se refresca 4 veces por segundo; no usa red. */
function useClock(): number {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 250);
    return () => clearInterval(id);
  }, []);
  return now;
}

function ListScreen({
  accounts,
  now,
  onAdd,
  onRemove,
}: {
  accounts: Account[];
  now: number;
  onAdd: () => void;
  onRemove: (a: Account) => void;
}) {
  const remaining = secondsRemaining(now);
  const urgent = remaining <= 5;

  return (
    <>
      <View style={styles.header}>
        <Text style={styles.title}>Authenticator</Text>
        <Pressable style={styles.addButton} onPress={onAdd} accessibilityLabel="Agregar cuenta">
          <Text style={styles.addButtonText}>＋</Text>
        </Pressable>
      </View>

      <View style={styles.timer}>
        <View style={styles.progressTrack}>
          <View
            style={[
              styles.progressFill,
              { width: `${(remaining / PERIOD) * 100}%` },
              urgent && styles.progressUrgent,
            ]}
          />
        </View>
        <Text style={[styles.timerText, urgent && styles.urgentText]}>
          {remaining}s · ventana C = {timeStep(now)}
        </Text>
      </View>

      <FlatList
        data={accounts}
        keyExtractor={(a) => a.id}
        contentContainerStyle={styles.list}
        ListEmptyComponent={
          <Text style={styles.empty}>Sin cuentas. Pulsa ＋ para escanear el QR del backend o pegar la semilla.</Text>
        }
        renderItem={({ item }) => (
          <Pressable style={styles.card} onLongPress={() => onRemove(item)}>
            <Text style={styles.issuer}>{item.issuer || 'Sin emisor'}</Text>
            <Text style={styles.accountName}>{item.account}</Text>
            <Text style={[styles.code, urgent && styles.urgentText]}>{formatCode(safeTotp(item.secret, now))}</Text>
          </Pressable>
        )}
      />
      <Text style={styles.hint}>Mantén presionada una cuenta para eliminarla</Text>
    </>
  );
}

function AddScreen({
  onAdd,
  onCancel,
  onScan,
}: {
  onAdd: (a: Omit<Account, 'id'>) => void;
  onCancel: () => void;
  onScan: () => void;
}) {
  const [issuer, setIssuer] = useState('LabPatrones2FA');
  const [account, setAccount] = useState('');
  const [secret, setSecret] = useState('');

  const submit = () => {
    const input = secret.trim();
    try {
      // Se acepta tanto la semilla Base32 como la URI otpauth:// completa.
      if (input.toLowerCase().startsWith('otpauth://')) {
        onAdd(parseOtpAuthUri(input));
        return;
      }
      const clean = input.replace(/\s/g, '').toUpperCase();
      if (!isValidBase32Secret(clean)) {
        throw new Error('La semilla debe ser Base32 (A-Z, 2-7) de al menos 16 caracteres');
      }
      onAdd({ issuer: issuer.trim(), account: account.trim() || 'cuenta', secret: clean });
    } catch (err) {
      Alert.alert('Semilla inválida', (err as Error).message);
    }
  };

  return (
    <KeyboardAvoidingView style={styles.form} behavior={Platform.OS === 'ios' ? 'padding' : undefined}>
      <Text style={styles.title}>Agregar cuenta</Text>

      <Pressable style={styles.primaryButton} onPress={onScan}>
        <Text style={styles.primaryButtonText}>Escanear código QR</Text>
      </Pressable>

      <Text style={styles.divider}>o ingresa la semilla manualmente</Text>

      <Text style={styles.label}>Emisor</Text>
      <TextInput style={styles.input} value={issuer} onChangeText={setIssuer} placeholderTextColor="#6b7280" />
      <Text style={styles.label}>Cuenta</Text>
      <TextInput
        style={styles.input}
        value={account}
        onChangeText={setAccount}
        placeholder="usuario"
        autoCapitalize="none"
        placeholderTextColor="#6b7280"
      />
      <Text style={styles.label}>Semilla Base32 o URI otpauth://</Text>
      <TextInput
        style={[styles.input, styles.secretInput]}
        value={secret}
        onChangeText={setSecret}
        placeholder="JBSWY3DPEHPK3PXP..."
        autoCapitalize="characters"
        autoCorrect={false}
        multiline
        placeholderTextColor="#6b7280"
      />

      <View style={styles.row}>
        <Pressable style={styles.secondaryButton} onPress={onCancel}>
          <Text style={styles.secondaryButtonText}>Cancelar</Text>
        </Pressable>
        <Pressable style={[styles.primaryButton, styles.flex]} onPress={submit}>
          <Text style={styles.primaryButtonText}>Guardar</Text>
        </Pressable>
      </View>
    </KeyboardAvoidingView>
  );
}

function ScanScreen({ onScanned, onCancel }: { onScanned: (a: Omit<Account, 'id'>) => void; onCancel: () => void }) {
  const [permission, requestPermission] = useCameraPermissions();
  const handled = useRef(false);

  if (!permission) {
    return <View style={styles.form} />;
  }

  if (!permission.granted) {
    return (
      <View style={styles.form}>
        <Text style={styles.title}>Permiso de cámara</Text>
        <Text style={styles.empty}>Se necesita la cámara para leer el QR otpauth:// del backend.</Text>
        <Pressable style={styles.primaryButton} onPress={requestPermission}>
          <Text style={styles.primaryButtonText}>Conceder permiso</Text>
        </Pressable>
        <Pressable style={styles.secondaryButton} onPress={onCancel}>
          <Text style={styles.secondaryButtonText}>Volver</Text>
        </Pressable>
      </View>
    );
  }

  return (
    <View style={styles.flex}>
      <CameraView
        style={StyleSheet.absoluteFill}
        facing="back"
        barcodeScannerSettings={{ barcodeTypes: ['qr'] }}
        onBarcodeScanned={({ data }) => {
          if (handled.current) return;
          handled.current = true;
          try {
            onScanned(parseOtpAuthUri(data));
          } catch (err) {
            Alert.alert('QR no válido', (err as Error).message, [
              { text: 'Reintentar', onPress: () => (handled.current = false) },
            ]);
          }
        }}
      />
      <View style={styles.scanOverlay}>
        <View style={styles.scanFrame} />
        <Pressable style={styles.secondaryButton} onPress={onCancel}>
          <Text style={styles.secondaryButtonText}>Cancelar</Text>
        </Pressable>
      </View>
    </View>
  );
}

function safeTotp(secret: string, now: number): string {
  try {
    return totp(secret, now);
  } catch {
    return '------';
  }
}

function formatCode(code: string): string {
  return `${code.slice(0, 3)} ${code.slice(3)}`;
}

const colors = {
  bg: '#0f1115',
  card: '#1b1e25',
  border: '#2c313c',
  text: '#f2f4f7',
  muted: '#9aa1ad',
  accent: '#6f93ff',
  urgent: '#ff7a6b',
};

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.bg, paddingTop: Platform.OS === 'android' ? 40 : 56 },
  flex: { flex: 1 },
  header: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', paddingHorizontal: 20 },
  title: { color: colors.text, fontSize: 26, fontWeight: '700', marginBottom: 8 },
  addButton: {
    width: 44,
    height: 44,
    borderRadius: 22,
    backgroundColor: colors.accent,
    alignItems: 'center',
    justifyContent: 'center',
  },
  addButtonText: { color: colors.bg, fontSize: 24, fontWeight: '700' },
  timer: { paddingHorizontal: 20, marginTop: 12 },
  progressTrack: { height: 8, borderRadius: 4, backgroundColor: colors.border, overflow: 'hidden' },
  progressFill: { height: 8, backgroundColor: colors.accent },
  progressUrgent: { backgroundColor: colors.urgent },
  timerText: { color: colors.muted, marginTop: 6, fontVariant: ['tabular-nums'] },
  urgentText: { color: colors.urgent },
  list: { padding: 20, gap: 12 },
  card: { backgroundColor: colors.card, borderRadius: 14, padding: 18, borderWidth: 1, borderColor: colors.border },
  issuer: { color: colors.accent, fontWeight: '600', fontSize: 14 },
  accountName: { color: colors.muted, fontSize: 14 },
  code: {
    color: colors.text,
    fontSize: 48,
    fontWeight: '700',
    letterSpacing: 4,
    marginTop: 6,
    fontVariant: ['tabular-nums'],
  },
  empty: { color: colors.muted, textAlign: 'center', marginVertical: 24, fontSize: 16, lineHeight: 22 },
  hint: { color: colors.muted, textAlign: 'center', paddingBottom: 24, fontSize: 12 },
  form: { flex: 1, padding: 20, gap: 8 },
  label: { color: colors.muted, marginTop: 8 },
  input: {
    backgroundColor: colors.card,
    color: colors.text,
    borderColor: colors.border,
    borderWidth: 1,
    borderRadius: 10,
    padding: 12,
    fontSize: 16,
  },
  secretInput: { minHeight: 70, fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace' },
  divider: { color: colors.muted, textAlign: 'center', marginVertical: 12 },
  row: { flexDirection: 'row', gap: 10, marginTop: 16 },
  primaryButton: { backgroundColor: colors.accent, borderRadius: 10, padding: 14, alignItems: 'center' },
  primaryButtonText: { color: colors.bg, fontWeight: '700', fontSize: 16 },
  secondaryButton: {
    borderColor: colors.border,
    borderWidth: 1,
    borderRadius: 10,
    padding: 14,
    alignItems: 'center',
    backgroundColor: colors.card,
  },
  secondaryButtonText: { color: colors.text, fontWeight: '600', fontSize: 16 },
  scanOverlay: { flex: 1, justifyContent: 'space-between', alignItems: 'center', padding: 40 },
  scanFrame: { width: 240, height: 240, borderWidth: 3, borderColor: colors.accent, borderRadius: 16, marginTop: 80 },
});
