import { StatusBar } from 'expo-status-bar';
import * as WebBrowser from 'expo-web-browser';
import { useEffect, useState } from 'react';
import { ActivityIndicator, Platform, Pressable, StyleSheet, Text, View } from 'react-native';
import { SafeAreaProvider, SafeAreaView } from 'react-native-safe-area-context';

import { authService } from './src/auth/authService';
import { useSession } from './src/auth/useSession';
import { AuthenticatorScreen } from './src/screens/AuthenticatorScreen';
import { HomeScreen } from './src/screens/HomeScreen';
import { LoginScreen } from './src/screens/LoginScreen';
import { VaultScreen } from './src/screens/VaultScreen';
import { TotpProvider } from './src/totp/TotpContext';
import { colors, space } from './src/ui/theme';

// Web: si esta pestaña es la ventana emergente que volvió a /callback, le entrega la URL
// (con code y state) a la ventana principal y se cierra. En nativo no hace nada.
WebBrowser.maybeCompleteAuthSession();

const isAuthPopup =
  Platform.OS === 'web' && typeof window !== 'undefined' && !!window.opener && window.location.pathname === '/callback';

type Tab = 'home' | 'authenticator' | 'vault';
const TABS: Array<{ key: Tab; label: string; icon: string }> = [
  { key: 'home', label: 'Inicio', icon: '🏠' },
  { key: 'authenticator', label: 'Authenticator', icon: '🔢' },
  { key: 'vault', label: 'Bóveda', icon: '🔐' },
];

function SignedInApp() {
  const [tab, setTab] = useState<Tab>('home');
  return (
    <View style={styles.flex}>
      <View style={styles.flex}>
        {tab === 'home' && <HomeScreen />}
        {tab === 'authenticator' && <AuthenticatorScreen />}
        {tab === 'vault' && <VaultScreen />}
      </View>
      <SafeAreaView edges={['bottom']} style={styles.tabBar}>
        {TABS.map((t) => {
          const active = t.key === tab;
          return (
            <Pressable
              key={t.key}
              onPress={() => setTab(t.key)}
              style={styles.tab}
              accessibilityRole="tab"
              accessibilityState={{ selected: active }}
            >
              <Text style={styles.tabIcon}>{t.icon}</Text>
              <Text style={[styles.tabLabel, active && styles.tabLabelActive]}>{t.label}</Text>
            </Pressable>
          );
        })}
      </SafeAreaView>
    </View>
  );
}

function Root() {
  const { status } = useSession();
  const [showAuthenticator, setShowAuthenticator] = useState(false);

  useEffect(() => {
    void authService.restoreSession(); // refresh silencioso si hay refresh_token guardado
  }, []);

  if (status === 'loading') {
    return (
      <View style={styles.center}>
        <ActivityIndicator color={colors.brand} size="large" />
      </View>
    );
  }
  if (status === 'signedIn') return <SignedInApp />;
  if (showAuthenticator) return <AuthenticatorScreen onBack={() => setShowAuthenticator(false)} />;
  return <LoginScreen onOpenAuthenticator={() => setShowAuthenticator(true)} />;
}

export default function App() {
  if (isAuthPopup) {
    return (
      <View style={styles.center}>
        <ActivityIndicator color={colors.brand} />
        <Text style={{ color: colors.muted, marginTop: space.md }}>Completando inicio de sesión…</Text>
      </View>
    );
  }
  return (
    <SafeAreaProvider>
      <TotpProvider>
        <StatusBar style="dark" />
        <View style={styles.app}>
          <Root />
        </View>
      </TotpProvider>
    </SafeAreaProvider>
  );
}

const styles = StyleSheet.create({
  app: { flex: 1, backgroundColor: colors.bg },
  flex: { flex: 1 },
  center: { flex: 1, alignItems: 'center', justifyContent: 'center', backgroundColor: colors.bg },
  tabBar: {
    flexDirection: 'row',
    backgroundColor: colors.surface,
    borderTopWidth: StyleSheet.hairlineWidth,
    borderTopColor: colors.line,
  },
  tab: { flex: 1, alignItems: 'center', paddingVertical: space.sm, gap: 2 },
  tabIcon: { fontSize: 20 },
  tabLabel: { fontSize: 12, color: colors.muted, fontWeight: '600' },
  tabLabelActive: { color: colors.brand },
});
